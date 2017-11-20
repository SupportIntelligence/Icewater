
rule m2377_18993849cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.18993849cc000b32"
     cluster="m2377.18993849cc000b32"
     cluster_size="23"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['274adaed6e3f46add8bd2f06de3778e4','2e5f622d2f727ec73440b1be111f48cf','b2f39544a094dba0dc17bd9267596887']"

   strings:
      $hex_string = { 772aaedd9b41cf9cd6a4286bb2a1077ff07d82f5ee7117b9fe46d242537c31294725e91e1d95f11adad98aa6743defd3955e544355eac8898ee60a2124e78472 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
