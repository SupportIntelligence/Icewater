
rule n3e9_199d6b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.199d6b49c0000b12"
     cluster="n3e9.199d6b49c0000b12"
     cluster_size="13792"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt manbat injector"
     md5_hashes="['001226882992e26b88afcf60222c3692','0016af4eb5ed910d237f05b34874d991','00a64e5ad9a6f4a773eb9d6aea3d72a2']"

   strings:
      $hex_string = { 70258b1abf70f0436c5683b4bbd7890193172eaff89703fa65c47140f27d9c8991008de9a9f4b88775ba0201dd531c18dacc265e6f1cf74ddb5fd6b43023ad41 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
