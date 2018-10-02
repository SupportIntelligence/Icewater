
rule n26bb_3636c31ce997b332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3636c31ce997b332"
     cluster="n26bb.3636c31ce997b332"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious ursu filetour"
     md5_hashes="['1442dcb5321112c87343f9f0d9ba87720efda0e0','25a245f4fb31a0f25a878235db9a41da41460d1e','2c3a5a429e6b2f91462fa8013140938eb6b4224d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3636c31ce997b332"

   strings:
      $hex_string = { 40fd82521ad79517a4fca742e9aa6088ce09c13a3e26dcaf6aff89bf6de3c08777167c8cdc2234d265f7652b537ec45d470b8b16919d11507592df286f18c87b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
