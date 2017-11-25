
rule m3e9_3115c8de913d4b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3115c8de913d4b10"
     cluster="m3e9.3115c8de913d4b10"
     cluster_size="52"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi wbna"
     md5_hashes="['0218b5d10370709ce7d4ef49e91efc98','107de5f31465257876950d708f3a1c14','b837ad488ac0357e8bdbc245b48b5f89']"

   strings:
      $hex_string = { 5e4648997f809e828393797ba48a8bac9493ccb2b1e7d7d5b49ea073524ed69523dea12faf7f23120f08e6ae38e5ab35b58529f2e9e4fdfcecfdf3e3fdf0dbf8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
