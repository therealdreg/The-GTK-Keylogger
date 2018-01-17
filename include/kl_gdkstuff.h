#ifndef __KL_GDKSTUFF
  #define __KL_GDKSTUFF

  /*
   * GDK Enums, types and all the stuff needed for hook handlers...
   */

  typedef enum
  {
    GDK_NOTHING		= -1,
    GDK_DELETE		= 0,
    GDK_DESTROY		= 1,
    GDK_EXPOSE		= 2,
    GDK_MOTION_NOTIFY	= 3,
    GDK_BUTTON_PRESS	= 4,
    GDK_2BUTTON_PRESS	= 5,
    GDK_3BUTTON_PRESS	= 6,
    GDK_BUTTON_RELEASE	= 7,
    GDK_KEY_PRESS		= 8,
    GDK_KEY_RELEASE	= 9,
    GDK_ENTER_NOTIFY	= 10,
    GDK_LEAVE_NOTIFY	= 11,
    GDK_FOCUS_CHANGE	= 12,
    GDK_CONFIGURE		= 13,
    GDK_MAP		= 14,
    GDK_UNMAP		= 15,
    GDK_PROPERTY_NOTIFY	= 16,
    GDK_SELECTION_CLEAR	= 17,
    GDK_SELECTION_REQUEST = 18,
    GDK_SELECTION_NOTIFY	= 19,
    GDK_PROXIMITY_IN	= 20,
    GDK_PROXIMITY_OUT	= 21,
    GDK_DRAG_ENTER        = 22,
    GDK_DRAG_LEAVE        = 23,
    GDK_DRAG_MOTION       = 24,
    GDK_DRAG_STATUS       = 25,
    GDK_DROP_START        = 26,
    GDK_DROP_FINISHED     = 27,
    GDK_CLIENT_EVENT	= 28,
    GDK_VISIBILITY_NOTIFY = 29,
    GDK_NO_EXPOSE		= 30,
    GDK_SCROLL            = 31,
    GDK_WINDOW_STATE      = 32,
    GDK_SETTING           = 33,
    GDK_OWNER_CHANGE      = 34,
    GDK_GRAB_BROKEN       = 35,
    GDK_DAMAGE            = 36,
    GDK_EVENT_LAST        /* helper variable for decls */
  } GdkEventType;

  struct _GdkEventKey
  {
    GdkEventType type;
    void *window;
    char send_event;
    unsigned int time;
    unsigned int state;
    unsigned int keyval;
    int length;
    char *string;
    unsigned short hardware_keycode;
    unsigned char group;
    unsigned int is_modifier : 1;
  };

  typedef struct _GdkEventKey GdkEventKey;

#endif
