
rule m3e9_3819521cc5eb0b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3819521cc5eb0b22"
     cluster="m3e9.3819521cc5eb0b22"
     cluster_size="23714"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi small virut"
     md5_hashes="['0003cc1a811c9c67560e13a7f3d15f66','00057da1753811199008cafdc97ebdf5','0050837a540bc14cf86ae0934e8e9c0e']"

   strings:
      $hex_string = { 5cd11a8f50c5be44343972d3de0914870afd00bbb6716c6fe26558a38ed9c457bacdb08b66411c3f923508733ea974276a9d605b1611cc0f4205b843ee7924f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
