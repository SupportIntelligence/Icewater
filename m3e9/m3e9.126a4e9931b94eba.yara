
rule m3e9_126a4e9931b94eba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.126a4e9931b94eba"
     cluster="m3e9.126a4e9931b94eba"
     cluster_size="2772"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore abbb autorun"
     md5_hashes="['0023df5ba5ff7d3a7f86ac261771ae68','00278c521d523d16570340c475a8ba9c','021527a0a30af00b9afc7c25843aef11']"

   strings:
      $hex_string = { ffa72e3f6ff4446232c747001c202d91e1fc35414e37baec39fde911dfceedf06b451a13e3ca3126e738db27dc9b2ccd753d95c1f80f846a210e06bedea3e05e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
