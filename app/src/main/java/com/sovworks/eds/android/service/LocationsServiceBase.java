package com.sovworks.eds.android.service;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.os.SystemClock;
import androidx.core.app.NotificationCompat;

import com.sovworks.eds.android.EdsApplicationBase;
import com.sovworks.eds.android.Logger;
import com.sovworks.eds.android.R;
import com.sovworks.eds.android.filemanager.activities.FileManagerActivity;
import com.sovworks.eds.android.helpers.CompatHelper;
import com.sovworks.eds.android.helpers.TempFilesMonitor;
import com.sovworks.eds.android.helpers.WipeFilesTask;
import com.sovworks.eds.android.locations.activities.CloseLocationsActivity;
import com.sovworks.eds.android.settings.UserSettings;
import com.sovworks.eds.fs.util.SrcDstRec;
import com.sovworks.eds.fs.util.SrcDstSingle;
import com.sovworks.eds.fs.util.Util;
import com.sovworks.eds.locations.EDSLocation;
import com.sovworks.eds.locations.Location;
import com.sovworks.eds.locations.LocationsManager;
import com.sovworks.eds.settings.Settings;

import java.io.IOException;

public class LocationsServiceBase extends Service
{
	public static final int NOTIFICATION_RUNNING_SERVICE = 1;

	public static void startService(Context context)
	{
		context.startService(new Intent(context, LocationsService.class));
	}

	public static void stopService(Context context)
	{
		context.stopService(new Intent(context, LocationsService.class));
	}

	public static final String ACTION_CHECK_INACTIVE_LOCATION = "com.sovworks.eds.android.CHECK_INACTIVE_LOCATION";

	public static class InactivityCheckReceiver extends BroadcastReceiver
	{
		@Override
		public void onReceive(Context context, Intent intent)
		{
			try
			{
				LocationsManager lm = LocationsManager.getLocationsManager(context, false);
				if(lm == null)
					return;
				Uri uri = intent.getParcelableExtra(LocationsManager.PARAM_LOCATION_URI);
				if(uri!=null)
				{
					EDSLocation loc = (EDSLocation) lm.getLocation(uri);
					closeIfInactive(context, loc);
				}

			}
			catch (Throwable e)
			{
				Logger.log(e);
			}
		}

		private void closeIfInactive(Context context, EDSLocation loc)
		{
			int tm = loc.getExternalSettings().getAutoCloseTimeout();
			Logger.debug("Checking if " + loc.getTitle() + " container is inactive");
			if(tm <= 0)
				return;
			long ct = SystemClock.elapsedRealtime();
			Logger.debug("Current time = " + ct);
			if(loc.isOpenOrMounted())
			{
				long lastActivityTime = loc.getLastActivityTime();
				Logger.debug("Container " + loc.getTitle() + " is open. Last activity time is " + lastActivityTime);
				if(ct - lastActivityTime > tm)
				{
					Logger.debug("Starting close container task for " + loc.getTitle() + " after inactivity timeout.");
					FileOpsService.closeContainer(context, loc);
					return;
				}
			}
			registerInactiveContainerCheck(context, loc);

		}
	}

	public static void registerInactiveContainerCheck(Context context, EDSLocation loc)
	{

        long triggerTime = loc.getExternalSettings().getAutoCloseTimeout();
        if(triggerTime == 0)
            return;
        triggerTime += SystemClock.elapsedRealtime();
        Intent i = new Intent(ACTION_CHECK_INACTIVE_LOCATION);
        i.putExtra(LocationsManager.PARAM_LOCATION_URI, loc.getLocationUri());
        PendingIntent pi = PendingIntent.getBroadcast(
                context,
                loc.getId().hashCode(),
                i,
                PendingIntent.FLAG_ONE_SHOT
        );
		LocationsService.setCheckTimer(context, pi, triggerTime);
	}

	/**
	 * The inactivity auto-close used AlarmManager.set(), which the platform is free to
	 * batch and which Doze defers outright. A container that should have closed after five
	 * minutes could therefore stay open for as long as the device stayed idle, which is
	 * exactly the state the timeout exists for. setExactAndAllowWhileIdle fires through
	 * Doze and needs no SCHEDULE_EXACT_ALARM permission (that gate is on setExact and
	 * setAlarmClock), so this costs nothing in the manifest.
	 */
	protected static void setCheckTimer(Context context, PendingIntent pi, long triggerTime)
	{
		AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
		if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
			am.setExactAndAllowWhileIdle(
					AlarmManager.ELAPSED_REALTIME_WAKEUP,
					triggerTime,
					pi
			);
		else
			am.set(
					AlarmManager.ELAPSED_REALTIME_WAKEUP,
					triggerTime,
					pi
			);
	}

	@Override
    public void onCreate()
	{
		super.onCreate();
        try
        {
            _locationsManager = LocationsManager.getLocationsManager(this, true);
            _settings = UserSettings.getSettings(this);
            _shutdownReceiver = new BroadcastReceiver()
            {
                @Override
                public void onReceive(Context context, Intent intent)
                {
                    Logger.debug("Device shutdown. Closing locations");
                    _locationsManager.closeAllLocations(true, false);
                }
            };
            registerReceiver(_shutdownReceiver, new IntentFilter(Intent.ACTION_SHUTDOWN));
			registerReceiver(_shutdownReceiver, new IntentFilter("android.intent.action.QUICKBOOT_POWEROFF"));
			InactivityCheckReceiver icr = new InactivityCheckReceiver();
			registerReceiver(icr, new IntentFilter(ACTION_CHECK_INACTIVE_LOCATION));
			// Assigned only after the register returns. A field set before the call means
			// "non-null but never registered" is reachable, and onDestroy then throws
			// IllegalArgumentException on the unregister. See onDestroy for why that
			// mattered: the teardown that closes the containers is downstream of it.
			_inactivityCheckReceiver = icr;
			// ACTION_SCREEN_OFF is one of the broadcasts the platform refuses to deliver to a
			// manifest-declared receiver, so this can only be registered from running code.
			// The service is the right place: it exists exactly as long as something is open,
			// which is exactly as long as there is anything to close.
			BroadcastReceiver sor = new BroadcastReceiver()
			{
				@Override
				public void onReceive(Context context, Intent intent)
				{
					if(_settings == null || !_settings.lockOnScreenOff())
						return;
					Logger.debug("Screen turned off. Closing locations");
					// forceClose, deliberately. A container left mounted past a locked screen
					// is readable by whoever picks the device up, and an open file handle is
					// not a reason to keep it that way.
					_locationsManager.closeAllLocations(true, true);
					forgetResidentKeys(context);
				}
			};
			// No RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED flag: that is required from
			// targetSdk 34 and this app is held at 28. Raising targetSdk in M2 must add
			// ContextCompat.registerReceiver(..., RECEIVER_NOT_EXPORTED) at all eighteen
			// call sites in this tree, or the app crashes on first start on Android 14.
			registerReceiver(sor, new IntentFilter(Intent.ACTION_SCREEN_OFF));
			_screenOffReceiver = sor;
        }
        catch (Exception e)
        {
            Logger.showAndLog(this, e);
        }
    }


	@Override
	public IBinder onBind(Intent intent)
	{
		return null;
	}
	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId)
	{		
		super.onStartCommand(intent, flags, startId);
        if(hasOpenLocations())
        {
            startForeground(
                    NOTIFICATION_RUNNING_SERVICE,
                    getServiceRunningNotification());
            TempFilesMonitor.getMonitor(this).startChangesMonitor();
            return Service.START_STICKY;
        }
        stopSelf();
        return Service.START_NOT_STICKY;
	}
	
	/**
	 * Swiping the task out of recents kills the activity but NOT a started foreground
	 * service, so before this the containers stayed mounted with no window left to close
	 * them from except the notification. Upstream never implemented onTaskRemoved at all.
	 */
	/**
	 * Closing the containers is not the whole of a lock. Two pieces of key material outlive
	 * every location: the master password the user typed to unlock protected settings, and
	 * the 32 byte settings protection key derived from it. Both sit in process memory for as
	 * long as the process lives, so before this change a screen-off lock closed every
	 * container and left the master password sitting behind it.
	 *
	 * Both holders are cleared through their own methods, which close the buffer AND null the
	 * field. That second half is the part that matters. getSettingsProtectionKey memoises on
	 * "field is null", so erasing the buffer without nulling the field would leave the cache
	 * looking populated while pointing at a dead id: the next protected read reaches
	 * SimpleCrypto.decrypt, which throws "key is closed", and getProtectedData turns that into
	 * InvalidSettingsPassword. The app would tell the user their settings password is wrong
	 * when nothing of the sort had happened.
	 *
	 * SecureBuffer.closeAll() is deliberately NOT called here, and it still has no callers
	 * anywhere in the tree. It is a process-wide sweep of a static registry with no notion of
	 * whether a buffer is in use, and one of the seven SecureBuffer fields in this codebase is
	 * EDSLocationFormatterBase._password, held for the whole of a container creation. A KDF
	 * over several hundred thousand iterations is exactly the moment a screen times out, and
	 * the sweep would pull the passphrase out from under it. The targeted clears above reach
	 * the two buffers that actually outlive a lock; the rest are already erased by
	 * Location.close(), which closeAllLocations has just finished calling.
	 *
	 * Only re-derivation can fail, and only for a user who set a master password: with none
	 * set the key comes back from the device-local automatic password with nothing to type.
	 * For a user who did set one, being asked again after a lock IS the feature.
	 */
	private static void forgetResidentKeys(Context context)
	{
		try
		{
			EdsApplicationBase.clearMasterPassword();
			UserSettings.getSettings(context).clearSettingsProtectionKey();
		}
		catch (Throwable e)
		{
			// Never let this take the lock down with it: the containers are already closed by
			// the time this runs, and that is the half that protects the data.
			Logger.log(e);
		}
	}

	@Override
	public void onTaskRemoved(Intent rootIntent)
	{
		try
		{
			if(_settings != null && _settings.lockOnTaskRemoved() && _locationsManager != null)
			{
				Logger.debug("Task removed. Closing locations");
				_locationsManager.closeAllLocations(true, true);
				// Same reasoning as the screen-off path: swiping the app away is a lock, and a
				// lock that leaves the master password resident is half a lock. Not done in
				// onDestroy, which also runs when the last container is simply closed: that
				// would sign the user out of protected settings every time, which is more than
				// either preference asks for.
				forgetResidentKeys(this);
			}
		}
		catch(Throwable e)
		{
			Logger.log(e);
		}
		super.onTaskRemoved(rootIntent);
		// stopSelf so the service does not linger holding a notification for containers it
		// just closed. onDestroy still runs and still wipes the mirror.
		if(!hasOpenLocations())
			stopSelf();
	}

	@Override
	public void onDestroy()
	{
		Logger.debug("LocationsService onDestroy");
		stopForeground(true);
		// Unregistering is best effort and must never decide whether the containers get
		// closed. unregisterReceiver throws IllegalArgumentException for a receiver that
		// was never registered, and before this the first throw skipped closeAllLocations
		// and deleteMirror entirely: the service would die leaving volumes mounted and the
		// decrypted mirror on disk, which is the exact state onDestroy exists to prevent.
		_shutdownReceiver = unregisterQuietly(_shutdownReceiver);
		_inactivityCheckReceiver = unregisterQuietly(_inactivityCheckReceiver);
		_screenOffReceiver = unregisterQuietly(_screenOffReceiver);
		try
		{
			TempFilesMonitor.getMonitor(this).stopChangesMonitor();
		}
		catch(Throwable e)
		{
			Logger.log(e);
		}
		_locationsManager.closeAllLocations(true, true);
		deleteMirror();
		_settings = null;
		_locationsManager = null;
		super.onDestroy();
	}

	protected LocationsManager _locationsManager;
    protected Settings _settings;
	protected BroadcastReceiver _shutdownReceiver, _inactivityCheckReceiver, _screenOffReceiver;

	/** Returns null so the caller can write the field back in one line. */
	private BroadcastReceiver unregisterQuietly(BroadcastReceiver r)
	{
		if(r != null)
		{
			try
			{
				unregisterReceiver(r);
			}
			catch(Throwable e)
			{
				Logger.log(e);
			}
		}
		return null;
	}

	/**
	 * These are decrypted copies of the user's files. Util.deleteFiles only unlinks them,
	 * which leaves the plaintext on the media until the blocks are reused, and the
	 * per-container close path a few classes over has always wiped its own mirror with
	 * WipeFilesTask. This is the same content and now gets the same treatment; the two
	 * paths disagreeing was the bug.
	 *
	 * Falls back to the plain delete if the wipe itself fails, because a temp folder left
	 * on disk is worse than one deleted without an overwrite.
	 */
	private void deleteMirror()
	{
		Location l = null;
		try
		{
			l = FileOpsService.getSecTempFolderLocation(_settings.getWorkDir(),this);
			if(l == null || !l.getCurrentPath().exists())
				return;
			SrcDstRec sdr = new SrcDstRec(new SrcDstSingle(l, null));
			sdr.setIsDirLast(true);
			WipeFilesTask.wipeFilesRnd(
					null,
					TempFilesMonitor.getMonitor(this).getSyncObject(),
					true,
					sdr
			);
		}
		catch (Throwable e)
		{
			Logger.log(e);
			try
			{
				if(l != null)
					Util.deleteFiles(l.getCurrentPath());
			}
			catch (IOException e2)
			{
				Logger.showAndLog(this, e2);
			}
		}
	}

	protected boolean hasOpenLocations()
	{
		LocationsManager lm = LocationsManager.getLocationsManager(this);
		return lm.hasOpenLocations();
	}
	
	private Notification getServiceRunningNotification()
	{
        Intent i = new Intent(this, FileManagerActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CompatHelper.getServiceRunningNotificationsChannelId(this))
                .setContentTitle(getString(R.string.eds_service_is_running))
                .setSmallIcon(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP ? R.drawable.ic_notification_new : R.drawable.ic_notification)
                .setContentText("")
                .setContentIntent(PendingIntent.getActivity(this, 0, i, 0))
                .setOngoing(true)
				.addAction(
						R.drawable.ic_action_cancel,
						getString(R.string.close_all_containers),
						PendingIntent.getActivity(
								this,
								0,
								new Intent(this, CloseLocationsActivity.class),
								PendingIntent.FLAG_UPDATE_CURRENT
						)
				);
        Notification n = builder.build();
        n.flags |= Notification.FLAG_NO_CLEAR | Notification.FLAG_FOREGROUND_SERVICE;
		return n;
	}
}
