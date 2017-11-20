
rule k3e9_092b311e6a620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.092b311e6a620912"
     cluster="k3e9.092b311e6a620912"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jeefo hidrag clfcen"
     md5_hashes="['11ac349fb5807a3629abd13a364c943f','227c57cd7d1631318b4f842937d92890','872cd53a0ecc31f357cfa0d9247642f3']"

   strings:
      $hex_string = { 6bde6dd76fd3719273bc75e577eb79ee7b9c7dce7ff281f183e785eb87fb89fd8bac8df48fff910493b495ed970199089bcf9dd09fc0a1f5a309a518a71ea913 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
