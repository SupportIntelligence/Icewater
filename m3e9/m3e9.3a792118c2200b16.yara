
rule m3e9_3a792118c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a792118c2200b16"
     cluster="m3e9.3a792118c2200b16"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob chir"
     md5_hashes="['293f9ce071cd43b2d62987f55ad0386f','569cffa419bee4a4fd3228eb3fdda510','e4f245281d578eb3aa535d68a6d76d9c']"

   strings:
      $hex_string = { 433b3b3d3f312d493a2b24543a2b26653d2f2d7d3c2f2b94392722a5443f41bc5b6d7ed8546ca2ea6188c7f66289c6f8638bc7f8494a5ae338251fc038292695 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
