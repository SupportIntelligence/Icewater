
rule m3e9_154a63e0cee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.154a63e0cee30b12"
     cluster="m3e9.154a63e0cee30b12"
     cluster_size="187"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys zbot injector"
     md5_hashes="['00487147a5ea8c40a6dfeec25dde6754','0185ddf12be15dc84821f39544df5694','1e4670fab1ec22c88e0f256490e5271c']"

   strings:
      $hex_string = { 58af8cd170aca0f3a7e8bd73d857eb5439a39ea6d105b819168640bcefd93c89c979950eaac52adafacb6df10269ce6cf299e7d0cce900d526fe0277f12a2337 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
