using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEditor.Scripting.Python;

[SelectionBase]
public class Export : MonoBehaviour
{
    public string item = "stone_bricks";

    private string nbt;

    private string enemyNBT = "empty";
    private string entrancesNBT = "empty";

    //[state1<location, yaw, mob>],[state2<location>]
    //[<0+ 0+ 0+ 90+ zombie>,<1+ 1+ 1+ 90+ husk>]-[<2+ 2+ 2+ 90+ skeleton>]

    // north-<1, 2, 3>=south-<4, 5, 6>

    public void ExportItem()
    {
        Vector3 origin = transform.GetChild(0).position;
        Vector3 end = transform.GetChild(1).position;
        Vector3 dirToEnd = end - origin;

        #region GetEntrancesNBT

        Transform entrances = transform.GetChild(2);

        for (int i = 0; i < entrances.childCount; i++)
        {
            Transform ent = entrances.GetChild(i);

            string facingDir = ent.gameObject.name;
            Vector3 dirToEnt = ent.position - origin;

            if (i > 0)
                entrancesNBT += "=";

            if (i == 0)
                entrancesNBT = $"{facingDir}-<{Round(Mathf.Abs(dirToEnt.x))},{Round(dirToEnt.y)},{Round(Mathf.Abs(dirToEnt.z))}>";
            else
                entrancesNBT += $"{facingDir}-<{Round(Mathf.Abs(dirToEnt.x))},{Round(dirToEnt.y)},{Round(Mathf.Abs(dirToEnt.z))}>";
        }

        #endregion

        #region GetStateNBTs

        Transform enemy = transform.GetChild(3);

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
                
                Transform mob = state.GetChild(j);

                // (-x, +y, +z) need to make x positive
                Vector3 dir = mob.position - origin;
                float yaw = mob.eulerAngles.y;
                string mobSelected = mob.GetComponent<SelectMob>().mob.ToString();

                if (j > 0)
                    enemyNBT += "=";
                
                enemyNBT += $"<{Round(Mathf.Abs(dir.x))},{Round(dir.y)},{Round(Mathf.Abs(dir.z))},{Round(yaw)},{mobSelected}>";
            }

            enemyNBT = enemyNBT + "]";

        }

        #endregion


        nbt = "{" +
            "id:\"minecraft:" + item + "\"," +
            "Count:1b," +
            "tag:{PublicBukkitValues:{" +
                "\"hypercube:x\":" + Round(Mathf.Abs(dirToEnd.x) + 1f) + ".d," +
                "\"hypercube:y\":" + Round(dirToEnd.y + 1f) + ".d," +
                "\"hypercube:z\":" + Round(Mathf.Abs(dirToEnd.z) + 1f) + ".d," +
                "\"hypercube:entrances\":\"" + entrancesNBT + "\"," +
                "\"hypercube:enemystate\":\"" + enemyNBT + "\"}}}";

        Debug.Log("Create File");

        System.IO.File.WriteAllText($"{Application.dataPath}/DFWebsocket/nbt.txt", nbt);

        PythonRunner.RunFile($"{Application.dataPath}/DFWebsocket/main.py");
    }

    float Round(float number)
    {
        return Mathf.Round(number * 10f) / 10f;
    }
}


