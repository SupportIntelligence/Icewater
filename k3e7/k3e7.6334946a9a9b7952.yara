import "hash"

rule k3e7_6334946a9a9b7952
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.6334946a9a9b7952"
     cluster="k3e7.6334946a9a9b7952"
     cluster_size="308 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit corrupt corruptfile"
     md5_hashes="['9329163c0536ae4939a0a38976e40ae9', 'a3bd7d524c36f197dd7b53d4fb5b1907', '48e00089b1a3b8d76cb9bad991e57db7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(57344,1024) == "0a19c8f211a8285cb39814dbe8c33d19"
}

