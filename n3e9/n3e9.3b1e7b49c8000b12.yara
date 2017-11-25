
rule n3e9_3b1e7b49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1e7b49c8000b12"
     cluster="n3e9.3b1e7b49c8000b12"
     cluster_size="26"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply generickd malicious"
     md5_hashes="['056765d3cb2fe6367b234ca0818d7eee','277a586426b29a12662d9970a4977bdc','a138ae286c327f70f73e873ab276d6a9']"

   strings:
      $hex_string = { 496d6167654c6973745f416464000000536176654443000056617269616e74436f70790000004765744443000000566572517565727956616c75654100000000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
