
rule m2377_2b93130289456d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b93130289456d16"
     cluster="m2377.2b93130289456d16"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0db806f4d5adbbca889d95437e2a553b','729001e644e0f8e619db876ab0e199e6','dcc9b13d8b8c8bbd7cb98c608897400d']"

   strings:
      $hex_string = { 6e65772d6175746f6d6f746976652e626c6f6773706f742e64652f7365617263682f6c6162656c2f494d475f30393431273e494d475f303934313c2f613e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
