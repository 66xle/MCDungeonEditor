using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor;
using UnityEditor.Scripting.Python;
using System.IO;


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

public class Export : MonoBehaviour
{
    public string item = "stone_bricks";

    private string nbt;

    private string enemyNBT = "empty";

    //[state1<location, yaw, mob>],[state2<location>]
    //[-0, 0, 0, 90, zombie-, -1, 1, 1, 90, husk-],[-2, 2, 2, 90, skeleton-,-3, 3, 3, 90, duck-]

    public void ExportItem()
    {
        #region GetStateNBTs

        Transform enemy = transform.GetChild(1);

        // Loop through states
        for (int i = 0; i < enemy.childCount; i++)
        {
            Transform state = enemy.GetChild(i);

            if (i < 1)
                enemyNBT = "[";
            else
                enemyNBT += "-[";

            // Loop through mobs in state
            for (int j = 0; j < state.childCount; j++)
            {
                Vector3 origin = transform.GetChild(0).position;
                Transform mob = state.GetChild(j);

                // (-x, +y, +z) need to make x positive
                Vector3 dir = mob.position - origin;
                float yaw = mob.eulerAngles.y;
                string mobSelected = mob.GetComponent<SelectMob>().mob.ToString();

                if (j > 0)
                    enemyNBT += ",";
                
                enemyNBT += $"<{Round(Mathf.Abs(dir.x))}+{Round(dir.y)}+{Round(dir.z)}+{Round(yaw)}+{mobSelected}>";
            }

            enemyNBT = enemyNBT + "]";

        }

        nbt = "{id:\"minecraft:" + item + "\",Count:1b,tag:{PublicBukkitValues:{\"hypercube:enemystate\":\"" + enemyNBT + "\"}}}";

        #endregion

        Debug.Log("Create File");

        System.IO.File.WriteAllText($"{Application.dataPath}/DFWebsocket/nbt.txt", nbt);

        PythonRunner.RunFile($"{Application.dataPath}/DFWebsocket/main.py");

    }

    float Round(float number)
    {
        return Mathf.Round(number * 10f) / 10f;
    }
}


