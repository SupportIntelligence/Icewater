
rule m3e9_46b0572683eb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.46b0572683eb1112"
     cluster="m3e9.46b0572683eb1112"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi jorik"
     md5_hashes="['066b5fd1e4a450363cb4ad8e4e7f319e','7594c3bf24e49a3cd0ab04b446f3e3a9','febeb633fa4308bef1bbe648b34bc948']"

   strings:
      $hex_string = { 8ab001fc63fbd21c0201fdf465005b44ff080800fd88b0011a44ff4b6d0727e0fe2700ff1b66006c0c00fbfe2340ff2a4620ff08080006ac014d30ff03400808 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
