
rule m3e9_316339674deb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339674deb1112"
     cluster="m3e9.316339674deb1112"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['3a98594cc0bc04cd21703c6c1f74c42b','4f5208ce7606e5491514f9888cd42e75','d3ceffd7099952e9aea8caf40a1b2ac7']"

   strings:
      $hex_string = { 7dba053bc344468b4f924732a755d82253ab4be731013489179ed0dfb5a41549f97221b8771fe897fdb49a3673102e6c88a5a382b9435fcf54f46d6ec79fe1da }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
