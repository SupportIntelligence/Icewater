
rule k3e9_29651862d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29651862d9eb1912"
     cluster="k3e9.29651862d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt symmi"
     md5_hashes="['3054f2312150048db01ac0d7d97f68bc','bbf34c0f7a66402f7345558222734842','e785cde6dfa989da13296e325ea65269']"

   strings:
      $hex_string = { 9bd6dc1e71ce629e39e028bdd7445b2d0d5672af89b23a1aac74735b1f75b31af36435aa2257e8c8c968df6cb447f66ebc1d8e5dfb43ba4b8a0bf57a54809169 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
