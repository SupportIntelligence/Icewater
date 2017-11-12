
rule n3e9_396e1099c2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396e1099c2220932"
     cluster="n3e9.396e1099c2220932"
     cluster_size="69"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic strictor orbus"
     md5_hashes="['0915d80efa26d05bb3a67a1b68a7187d','09d5877bc0e85e67a1be12c5bb970d86','a728688e037ca268ccfd6f8de20188fa']"

   strings:
      $hex_string = { 3f003000008800000010301f302c3036304d305730673071308b309230a230ad30c630cd30de30e5300331133122312c3143314d315c31693176318c31a231ac }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
