
rule m3f9_6d14dee9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.6d14dee9c4000b12"
     cluster="m3f9.6d14dee9c4000b12"
     cluster_size="77"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="abzf mofksys swisyn"
     md5_hashes="['130a54ca18a9ee9bde03bde563e99eb5','1339098d16ba76470f113efb5a4a4c84','5a992d4386d83611d769c1ab6db40d86']"

   strings:
      $hex_string = { b913541e8d6a886c1fb3dabbdad49a4a85331c68147020a5ffcc310005fa24c2bb95c80942a143a7e7ee0294d1ecfa32e5b34fb84b832860eb3911a9983a4fad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
