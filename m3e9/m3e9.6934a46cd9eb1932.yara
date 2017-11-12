
rule m3e9_6934a46cd9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6934a46cd9eb1932"
     cluster="m3e9.6934a46cd9eb1932"
     cluster_size="31809"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz xmjngup"
     md5_hashes="['00030d178500b1222a41d3eebebaefff','00049963d042db74153ec8965b5b12e1','0031cdcfe75e9689015353955d1a66a2']"

   strings:
      $hex_string = { e234d699262cbe7d78e5b8a2ef6459fb2ff0ed42f46039eef89019b1933bce0689b1e70475c814e1cbf7df12e0ba0967ec079de9def2033fa3f9f59701b0afb2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
