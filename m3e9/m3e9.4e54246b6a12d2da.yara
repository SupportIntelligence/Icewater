
rule m3e9_4e54246b6a12d2da
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4e54246b6a12d2da"
     cluster="m3e9.4e54246b6a12d2da"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob sality"
     md5_hashes="['0ccf7c567fe1db47c4a6b7b6f3ed5990','2a1f3e01fb7b86733f6f21d718e40553','d9325740aab9aeded4ce6b4f92582e4c']"

   strings:
      $hex_string = { 80e4e3d8f3aca398ea8b7d72e9736155df533e32ce432c1ec0371f12b53a2214af42291da7493428994d392b874c362975422e21643d261a583f261951473325 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
