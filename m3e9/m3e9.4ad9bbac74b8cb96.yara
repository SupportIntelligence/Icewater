
rule m3e9_4ad9bbac74b8cb96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4ad9bbac74b8cb96"
     cluster="m3e9.4ad9bbac74b8cb96"
     cluster_size="90"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="yakes ransom bitd"
     md5_hashes="['047ebd4331ea1f79259a4a1569fc116e','111477c481259bb114bf42447deb7a49','513cbb84b7accf1d18ef981424c44048']"

   strings:
      $hex_string = { c013be5bd46752e7e9805c99f6af8bc974481630e4c85a8aea065134bc8858590233668d1e56cca8a1c50c2dcba3283f86654575b0cda4b953f2c78777d3ddd9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
