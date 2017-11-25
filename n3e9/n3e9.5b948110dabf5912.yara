
rule n3e9_5b948110dabf5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5b948110dabf5912"
     cluster="n3e9.5b948110dabf5912"
     cluster_size="1189"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softpulse bundler driverupd"
     md5_hashes="['000419eedf9d3404844fc91c56775153','00194f32dec751c04bee6464ee783d7e','02d8d0e90acb14b3d42efec1eb6f7698']"

   strings:
      $hex_string = { 3b0b5c2a35a6fb4c01ac7d36411a63b1f4b9e7a7f12b877499c29271fd0497570602a211620cc3fa9a9010cfdc13556e3edfd324b7a9ec60198dad4e372617e8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
