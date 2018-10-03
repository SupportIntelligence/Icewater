
rule k26bb_03d39e98ca210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.03d39e98ca210932"
     cluster="k26bb.03d39e98ca210932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox malicious yontoo"
     md5_hashes="['f97ba0cddfd72ef5c7d7a42af5778cbb86bddecb','33a177028afba6e675340fc15a8e80ff5c2e3a5a','8625eedae33ddeffb697f93ec263ef45b8b53c22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.03d39e98ca210932"

   strings:
      $hex_string = { d9ec59d16de6ce0382f8193ed62b9187db10deb6955aa4660bf55dd880c5b3a7f1cb977cc7a5b057815d8dd2587f71c6372fbc6edfae232ef64631771ff98a76 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
