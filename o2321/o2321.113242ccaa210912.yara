
rule o2321_113242ccaa210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.113242ccaa210912"
     cluster="o2321.113242ccaa210912"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr unwanted"
     md5_hashes="['11012c29e63913648ca89b9a66a68c63','11c18e5429565398bb80d2af49ff9d30','e468517e52767ece270e542349277018']"

   strings:
      $hex_string = { b34b1077744aab2888726880f17f5a8ab9bd394d9ea7832f140a4e533840e942035df40c4358ef65c2f8e4f75f061af5bbfe6ea0acc0f2e221cf975be5440bbe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
