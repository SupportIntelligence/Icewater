
rule n2319_391a1ec1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.391a1ec1c4000912"
     cluster="n2319.391a1ec1c4000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['2b7a6b7a2e09bdacb1adcbdf6b0061ccae0af648','3626819d5eaf68a08bfd8d26dc0f6f764da85a2e','b04e42328b78a970a4a848f23bc4397392cf4635']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.391a1ec1c4000912"

   strings:
      $hex_string = { 6e74656e742e636f6d2f70726f78792f464b7354627a5261327967733832554f43764969364a3735393857573446644b42475a366a4d5348715870654739546c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
