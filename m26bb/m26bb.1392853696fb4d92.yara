
rule m26bb_1392853696fb4d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1392853696fb4d92"
     cluster="m26bb.1392853696fb4d92"
     cluster_size="88"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swisyn malicious susp"
     md5_hashes="['5e3df63e6302b54c826bfe9ab59364fc93b254c6','bc41b0cce39e873fe647f6f71dcf84f925776db0','a5732f9e6ea88f0b7fcdbe29765d99136a2fe43b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1392853696fb4d92"

   strings:
      $hex_string = { 8d7d8c6a0ff3a559be4c0600088dbd4cffffff837d0c00f3a566a5bbcc040008752f6844646b2068500100006a00ff15c40200088bf06a545933c08bfe81c6a8 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
