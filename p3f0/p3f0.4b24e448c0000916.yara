
rule p3f0_4b24e448c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f0.4b24e448c0000916"
     cluster="p3f0.4b24e448c0000916"
     cluster_size="61"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamemodding heuristic malicious"
     md5_hashes="['0a28c368e8d98efe54ae426251ef0319','0b731cef49d7f9283e56b37b39b7d753','42cfe5117c67f587631732a1c91c0861']"

   strings:
      $hex_string = { b63663c80b17bccfd200803f4b57f43802c1016a27cb1352c97fa54189b33373b2be8d0506042b624f48cca931e5a1dc50af54e15bc08cf8fe5eb4826b4e6f88 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
