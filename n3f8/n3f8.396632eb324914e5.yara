
rule n3f8_396632eb324914e5
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.396632eb324914e5"
     cluster="n3f8.396632eb324914e5"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smforw andr"
     md5_hashes="['a5c8d36cccee2a23cd328aa3b80ca42f2488ecab','3ec6ff961f664e79afee8fa440c5ebb2340b0baa','8e7170e55b9fbf7e608a2127009584e2bb1ead13']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.396632eb324914e5"

   strings:
      $hex_string = { 7e1c0000ce02f4057f1c0000cf02d80341010000cf027603db120000cf025f03ef190000cf024707361b0000d002ac06fa1a0000d102ac06281a0000d2024904 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
