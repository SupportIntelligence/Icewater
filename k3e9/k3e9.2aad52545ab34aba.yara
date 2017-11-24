
rule k3e9_2aad52545ab34aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2aad52545ab34aba"
     cluster="k3e9.2aad52545ab34aba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy tinba flmp"
     md5_hashes="['04a31bb4ca494619000b77f7bc93319b','081f90b9ed7ac73c506e98152e937fee','7f3dedc586aac9c5bbe18a1c1a904284']"

   strings:
      $hex_string = { 95acebf3ca57bdc63907f7ee382d810ba0d41a7fb1567858e32fd24409f5bbc868ae9869d9dd346d303303f08c422b993ee19a9f5fc90ff72a4853d005f9257c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
