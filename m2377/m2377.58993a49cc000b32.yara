
rule m2377_58993a49cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.58993a49cc000b32"
     cluster="m2377.58993a49cc000b32"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0001cca74d506706a074891a200b34f1','00c50219b94c2660da9f4ac0d157b298','636da88b79040f486cc524b4231b813c']"

   strings:
      $hex_string = { cbd6f23812c45f659f08529e4d7d167886e00d0cb2eee983967a2c612faa488b391034d071a4661fb353b5de605a624367932dc325bdc8ae136a6fe291d8813b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
