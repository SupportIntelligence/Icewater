import "hash"

rule k3e9_3c19a848c0010b10
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c19a848c0010b10"
     cluster="k3e9.3c19a848c0010b10"
     cluster_size="198 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zbot upatre generickd"
     md5_hashes="['5a0da1d4f905b1e029a422a3365a4e44', 'd50b8214a29a931e9a7c450e15196c68', 'ccf8afb167d81f3c39dd0235af5d990c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "9fa1d766c4dc195888a12c0d4c7c1e53"
}

