
rule o3e9_29b1585a9c926396
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29b1585a9c926396"
     cluster="o3e9.29b1585a9c926396"
     cluster_size="1153"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['005a5cb34d6e38daf4e840847b001c8f','01067ddd53a5c23b872772dab1762a36','04122fe6a29cb5db4dbfa66d617dc34d']"

   strings:
      $hex_string = { c873e735271bfad3cd9cbfb9765f7ce693cd9b919e2a1e36dcee2a96a409470283f696643065a6a1353b6d4ca279f83b7527f42a97456b2ba12103c5e4c9f68d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
