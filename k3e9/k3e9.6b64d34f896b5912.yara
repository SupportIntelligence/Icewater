import "hash"

rule k3e9_6b64d34f896b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f896b5912"
     cluster="k3e9.6b64d34f896b5912"
     cluster_size="66 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['dc8c24506d18edc86cc82b98ae4c18b7', 'b8f5917ffd13c0d03ffa125855b40ca7', '2cbae2e353727aa3f0342820455ec941']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

