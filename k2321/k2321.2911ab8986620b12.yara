
rule k2321_2911ab8986620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2911ab8986620b12"
     cluster="k2321.2911ab8986620b12"
     cluster_size="21"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['0c8a03e38a27714989a632caeb048378','177b3c5fc078ad38cb289950cb4c27e1','cb5446a1d5ba0486bfd775888f15fa42']"

   strings:
      $hex_string = { 68a5b926f3e5c6f044b7482ae451ce16f6eb55b4add7b07a699f91152bee6c5ae8dad28388ac618297b2d541546610c4a411179ec2cf81a349ba80d9e3858ec0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
