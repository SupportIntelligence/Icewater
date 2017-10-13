import "hash"

rule n3fa_3b9855a985e10b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.3b9855a985e10b12"
     cluster="n3fa.3b9855a985e10b12"
     cluster_size="12210 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="adsnare malicious cloud"
     md5_hashes="['056e1525b25d2c639f3de23fb5e734eb', '0261efa9a57a0f0db98e0b52833d74d4', '04edaff9b91bc27b1306990cdfb01a9b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(656896,1152) == "fe18f88aa6207b1ff9ed2c13dd42bf82"
}

