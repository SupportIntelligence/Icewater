
rule o3e9_2d1268d296927992
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2d1268d296927992"
     cluster="o3e9.2d1268d296927992"
     cluster_size="50"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['025b204e2a39eeff123c60a8805bd6c4','04346d58b0ca8b867815a07f1459ed64','4076edf53928433919ee579362baa829']"

   strings:
      $hex_string = { 8019b29cc3ba60588c1c7ed1073551a550dd4fe366ebd755389347ff654a25a0b8b4e2973e18a72032681fe1be3dbf6fd4c275cffa1e675236338769b3285e7d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
