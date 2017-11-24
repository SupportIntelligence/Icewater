
rule i3ed_051756abec288932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.051756abec288932"
     cluster="i3ed.051756abec288932"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue generickdz debris"
     md5_hashes="['008df18fceaef0320bb58af3330d7039','39afab57d3fe2f9bb0cb9b72fcb96c22','bff56305d5b77d04c0c93c1dbae38e7b']"

   strings:
      $hex_string = { 8d71fc3bf072128b0e85c97407ffd1a15030001083ee04ebea50ff151020001083255030001000595e6a0158c20c00558bec538b5d08568b750c578b7d1085f6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
