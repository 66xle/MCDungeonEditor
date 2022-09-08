using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor;

[CustomEditor(typeof(DungeonRoom))]
public class DungeonEditor : Editor
{
    public bool showPosition = true;
    public string status = "Select a GameObject";

    public override void OnInspectorGUI()
    {
        EditorGUILayout.Space();

        DungeonRoom room = (DungeonRoom)target;
        if (GUILayout.Button("Create Enemy State"))
        {
            room.CreateEnemyState();
        }

        ShowStates();

        //EditorGUILayout.PropertyField(serializedObject.FindProperty("states"));

        //serializedObject.ApplyModifiedProperties();
    }

    void ShowStates()
    {
        
    }
}
