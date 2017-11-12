
rule n3e9_396c9899c2220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.396c9899c2220932"
     cluster="n3e9.396c9899c2220932"
     cluster_size="127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic strictor orbus"
     md5_hashes="['05f7361287af614fa4a1ca1523c150d8','07a11f2a11d6f235de9f946138a939ff','442da666d3b67d29df785e7ae6e68aa1']"

   strings:
      $hex_string = { 3f003000008800000010301f302c3036304d305730673071308b309230a230ad30c630cd30de30e5300331133122312c3143314d315c31693176318c31a231ac }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
