
rule m3ed_15b85299c6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.15b85299c6220912"
     cluster="m3ed.15b85299c6220912"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bpchjo"
     md5_hashes="['18f8cadcfd1ef3529f8bd2655bf3c394','300d9ae23b609c194d4ca6bf8f2af14b','be64ce50ee12df6cc472a1ff1331aac4']"

   strings:
      $hex_string = { 42463ac374034f75f33bfb75108819e88cbdffff6a225989088bf1ebc133c05f5e5b5dc38bff558bec8b4d085633f63bce7c1e83f9027e0c83f9037514a12cf4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
