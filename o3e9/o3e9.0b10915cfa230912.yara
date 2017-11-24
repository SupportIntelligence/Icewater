
rule o3e9_0b10915cfa230912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b10915cfa230912"
     cluster="o3e9.0b10915cfa230912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr unwanted"
     md5_hashes="['1d5df1beb0edb412bae6eccd93b702af','2d792b7db5b010aa7b08ce0e0d499ae4','d5430a1927821b2696b33c74ffefb707']"

   strings:
      $hex_string = { 9f7335583ab788a514f08d205f9ca6433be957b51c70778ad66d07c1b2465393870fe7ad0b6ed55238d2abbc24def9252b4e72d729e69de57c320c80455de02f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
