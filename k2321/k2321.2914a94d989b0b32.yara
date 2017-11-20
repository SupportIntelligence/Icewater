
rule k2321_2914a94d989b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914a94d989b0b32"
     cluster="k2321.2914a94d989b0b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy tinba vbkrypt"
     md5_hashes="['5541ccd3685f2ce186fc023704727f93','860ecf58a73b4ad463e5f7e0dadb7d1e','efe21826309a80b4c811d6c157820721']"

   strings:
      $hex_string = { f5350c5c799a6bfd879a3e59cba0b608065a63889e21ac3d4ea57f93b1b7e2c79499cc72c99f73231953f85f3bf14f544de7785182b14482e32a619248bb0074 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
