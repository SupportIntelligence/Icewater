
rule k3fe_61369ce1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3fe.61369ce1c2000932"
     cluster="k3fe.61369ce1c2000932"
     cluster_size="357"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ransom democry cloud"
     md5_hashes="['00ef340ef251cd907da789273d9c15b2','01095b43f7fb447de613d2516ac2e9a3','0f1b088a7db67a51c033f074e30c4190']"

   strings:
      $hex_string = { e1072bd9d3ed83fb20731e85ff0f840c0d00000fb6068bcb83c308d3e0ffcf48ffc603e883fb2072e28bc50fb7cdf7d0c1e8103bc87418488d05a8eaffff41c7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
