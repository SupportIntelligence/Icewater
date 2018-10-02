
rule k26d7_565a8cb93a304a92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d7.565a8cb93a304a92"
     cluster="k26d7.565a8cb93a304a92"
     cluster_size="242"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hmlwco malicious riskware"
     md5_hashes="['dc761813e6f46116ab080aff610c061461b16f98','5b2fd6607269b775ae1cb0c54fd21080000b29f0','2b995c556b1289200c6e4f2b4789be035da46e1f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d7.565a8cb93a304a92"

   strings:
      $hex_string = { 33c085c9577e1c8b7e040fb7570239550c75080fb6173955fc74254083c7063bc17ce78d410183f80189461075236a066a00ff35f8b04000ff15e0a64000eb26 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
