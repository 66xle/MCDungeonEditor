using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor;

[CustomEditor(typeof(Export))]
public class ExportEditor : Editor
{
    public override void OnInspectorGUI()
    {
        EditorGUILayout.Space();

        EditorGUILayout.PropertyField(serializedObject.FindProperty("item"));

        EditorGUILayout.Space();

        Export room = (Export)target;
        if (GUILayout.Button("Export Item"))
        {
            room.ExportItem();
        }

        serializedObject.ApplyModifiedProperties();

    }
}
