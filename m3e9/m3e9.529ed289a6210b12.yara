
rule m3e9_529ed289a6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.529ed289a6210b12"
     cluster="m3e9.529ed289a6210b12"
     cluster_size="3408"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus wbna"
     md5_hashes="['00a8e54bc5536942baa3d4a17730eef1','00b76790564d2ccd6d278491688e7e73','034e24992e39d7fc7a04973a98bdf26e']"

   strings:
      $hex_string = { 682a560000e8df4bfeffff155810400068d0fc4100eb308b4df083e10485c974098d4dc8ff15201040008d55bc528d45c0506a02ff158411400083c40c8d4dac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
