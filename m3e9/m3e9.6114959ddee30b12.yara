
rule m3e9_6114959ddee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6114959ddee30b12"
     cluster="m3e9.6114959ddee30b12"
     cluster_size="228"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar diple"
     md5_hashes="['003e8d61762cff361f09ee73cd2669e9','0056568c10d87c99f466ca39b48d41cd','2d95391a3635e422b9b8cfd4ca835c21']"

   strings:
      $hex_string = { 0000008db5acf6ffff6a04ffb5fcf6ffffe827b2feff8bc88bd6e824b2feff8d85fcf6ffff50ff35fce04100ff35b8e14100e8833fffff8d85fcf6ffff506a00 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
