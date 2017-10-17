import "hash"

rule k3e9_5972ded34c001132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5972ded34c001132"
     cluster="k3e9.5972ded34c001132"
     cluster_size="94 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre generickd waski"
     md5_hashes="['bcc04f177aa2d5c08d414d54de041855', 'a700075b53ef8f404cb02b343c8aa5b0', 'cd5730d16f3a280cb2409bd4ebf83722']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(19201,1075) == "c4bff3ad14f9e4125c37f20a22b1d5fa"
}

