
rule m3ed_51d995491ee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.51d995491ee31932"
     cluster="m3ed.51d995491ee31932"
     cluster_size="63"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost bjlog backdoor"
     md5_hashes="['01534d5a0a03ab2afaae457efe8a7afc','0194ab177e831b15a29ecd01d441bb48','2ba55589fc131dd223a0f70e26c1e515']"

   strings:
      $hex_string = { 732a85ff0f843913000033c94f8a0e897c24148bd18bcdd3e283c50803c24683fd10894424108974241872d63c0889431074108b4c2454c74118e0370220e99c }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
