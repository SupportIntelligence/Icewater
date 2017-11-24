
rule m3e9_4854e11c85774e3a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4854e11c85774e3a"
     cluster="m3e9.4854e11c85774e3a"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi wbna"
     md5_hashes="['1a95cc76e077ef6a5ce1e6e576c709f9','1c9d6f93d1f1a6b04d7ab4b383f5440f','cdd4548cf82ce7035340c4f0ffb98325']"

   strings:
      $hex_string = { d945b8db45bcdd5d84dc4d84dfe0a80d0f8524020000e8970efdff8bf08d4dc4e8030efdff8b3b8b078d4dbc51ff75cc57ff90e4020000dbe285c07d1168e402 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
